package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/jlaffaye/ftp"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func main() {
	var addr = flag.String("addr", "127.0.0.1:8080", "http server")
	flag.Parse()

	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	log.SetFormatter(customFormatter)

	if os.Getenv("FTPTOOL_ADDRESS") != "" && os.Getenv("SERVER_PORT") != "" {
		*addr = fmt.Sprintf("%s:%s", os.Getenv("FTPTOOL_ADDRESS"), os.Getenv("SERVER_PORT"))
	}

	serveHTTP(*addr)
}

func getClient(config *serverConfig) (*ftp.ServerConn, error) {
	server := fmt.Sprintf("%s:%d", config.IP, config.Port)

	client, err := ftp.DialTimeout(server, 10*time.Second)
	if err != nil {
		return nil, err
	}

	log.Println("Successfully connected to", server)

	if err := client.Login(config.User, config.Password); err != nil {
		return nil, err
	}

	log.Println("Successfully login to", server)

	return client, nil
}

func registryLoginTest(req *TestRegistryRequest) error {
	if req.Repository == "" {
		return errors.New("empty Repository")
	}

	//host, port, err := net.SplitHostPort(req.Repository)
	//if err != nil {
	//	return fmt.Errorf("Invalid Repository %v", err)
	//}

	//cli, err := client.NewClient(req.Repository, "", nil, nil)
	cli, err := client.NewEnvClient()
	if err != nil {
		log.Errorf("docker NewClient error: %v", err)
		return err
	}
	defer cli.Close()

	authConfig := types.AuthConfig{
		Username:      req.Username,
		Password:      req.Userpwd,
		ServerAddress: req.Repository,
	}

	resp, err := cli.RegistryLogin(context.Background(), authConfig)
	if err != nil {
		log.Errorf("login error: %v", err)
		return err
	}

	fmt.Println(resp.Status)
	return nil
}

func connectTest(cfg *TestRequest) error {
	client, err := getClient(&serverConfig{
		IP:       cfg.ServerIP,
		Port:     cfg.ServerPort,
		User:     cfg.Username,
		Password: cfg.Userpwd,
	})
	if err != nil {
		return err
	}

	defer client.Quit()

	if err := client.ChangeDir(cfg.SyncDirectory); err != nil {
		if strings.HasPrefix(err.Error(), "550") {
			return fmt.Errorf("directory %s not exists", cfg.SyncDirectory)
		}
	}

	return nil
}

func retrFile(path string, config *serverConfig) (*ftp.Response, error) {
	log.Println("Retr file", path)

	client, err := getClient(config)
	if err != nil {
		return nil, err
	}
	defer client.Quit()

	if err := client.ChangeDir(filepath.Dir(path)); err != nil {
		log.Errorf("change to dir %s error: %v", filepath.Dir(path), err)
		return nil, err
	}

	return client.Retr(filepath.Base(path))
}

func saveFile(path string, r io.Reader) error {
	dest, err := os.Create(path)
	if err != nil {
		return err
	}
	defer dest.Close()

	if _, err = io.Copy(dest, r); err != nil {
		return err
	}

	return nil
}

func Walk(cfg *serverConfig, path string, walkFn func(string, time.Time) error) (err error) {
	var lines []*ftp.Entry

	log.Printf("Walking: '%s'\n", path)
	if lines, err = listFiles(cfg, path); err != nil {
		return
	}

	for _, line := range lines {
		switch line.Type {
		case 1:
			if err = Walk(cfg, filepath.Join(path, line.Name), walkFn); err != nil {
				return
			}
		case 0:
			if err = walkFn(filepath.Join(path, line.Name), line.Time); err != nil {
				return
			}
		}
	}

	return
}

func listFiles(cfg *serverConfig, path string) ([]*ftp.Entry, error) {
	server := fmt.Sprintf("%s:%d", cfg.IP, cfg.Port)

	client, err := ftp.Dial(server)
	if err != nil {
		return nil, err
	}
	defer client.Quit()

	log.Println("Successfully connected to", server)

	if err := client.Login(cfg.User, cfg.Password); err != nil {
		return nil, err
	}

	log.Println("Successfully login to", server)

	entries, err := client.List(path)
	if err != nil {
		log.Println("list error:", err)
		return nil, err
	}

	return entries, nil
}

func md5Check(md5Sum string, path string) bool {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	return hex.EncodeToString(h.Sum(nil)) == md5Sum
}

func downloadImage(src *ImageSource, image *ImageItem) (string, error) {
	cfg := &serverConfig{
		IP:       src.ServerIP,
		Port:     src.ServerPort,
		User:     src.Username,
		Password: src.Userpwd,
	}

	fname := image.ImageFileName + "#" + image.ImageTag + ".tar.gz"
	path := filepath.Join(image.ImageFileDirectory, fname)

	log.Println("download image", path)

	file, err := retrFile(path, cfg)
	if err != nil {
		log.Errorf("Retr file %s error: %v", path, err)
		return "", err
	}

	tmpPath := filepath.Join("/tmp", fname)
	if err := saveFile(tmpPath, file); err != nil {
		log.Errorf("Save file %s to %s error: %v", path, tmpPath, err)
		return "", err
	}

	return tmpPath, nil
}

func loadImage(path string) (string, error) {
	cli, err := client.NewEnvClient() //NewClientWithOpts()
	if err != nil {
		return "", err
	}
	defer cli.Close()

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	resp, err := cli.ImageLoad(context.Background(), f, false)
	if err != nil {
		return "", err
	}

	bts, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	out := bytes.Trim(bts, "\n")
	m := map[string]string{}
	if err := json.Unmarshal(out, &m); err != nil {
		log.Errorf("unmarshal err: %v", err)
		return "", err
	}

	return strings.TrimSuffix(strings.TrimPrefix(m["stream"], "Loaded image: "), "\n"), nil
}

func tagImage(src, repo, name, tag string) (string, error) {
	cli, err := client.NewEnvClient() //NewClientWithOpts()
	if err != nil {
		return "", err
	}
	defer cli.Close()

	image := fmt.Sprintf("%s:%s", strings.Replace(name, "#", "/", -1), tag)
	target := filepath.Join(repo, image)

	if err := cli.ImageTag(context.Background(), src, target); err != nil {
		return "", err
	}

	log.Printf("tag image %s to %s", src, target)

	return target, nil
}

func pushImage(username, password, image string) error {
	cli, err := client.NewEnvClient() //NewClientWithOpts()
	if err != nil {
		return err
	}
	defer cli.Close()

	authConfig := types.AuthConfig{
		Username: username,
		Password: password,
	}

	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return err
	}

	authStr := base64.URLEncoding.EncodeToString(encodedJSON)

	resp, err := cli.ImagePush(context.Background(), image, types.ImagePushOptions{RegistryAuth: authStr})
	if err != nil {
		return err
	}
	defer resp.Close()
	//io.Copy(os.Stdout, out)

	rd := bufio.NewReader(resp)
	for {
		str, err := rd.ReadString('\n')
		if err == io.EOF {
			break
		}

		if err != nil {
			log.Errorf("Read Error:", err)
			return err
		}

		if strings.Contains(str, "errorDetail") {
			return errors.New(strings.Trim(str, "\n"))
		}

		log.Println(strings.Trim(str, "\n"))
	}

	return nil
}

func readFile(cfg *serverConfig, path string) (string, error) {
	resp, err := retrFile(path, cfg)
	if err != nil {
		log.Errorf("retr file error: %v", err)
		return "", err
	}

	body, err := ioutil.ReadAll(resp)
	if err != nil {
		log.Errorf("read body error: %v", err)
		return "", err
	}

	return strings.TrimSuffix(string(body), "\n"), nil
}

func serveHTTP(addr string) {
	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "only support GET method", http.StatusForbidden)
			return
		}

		bytes, _ := json.Marshal(map[string]string{"status": "ok"})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(bytes)
	})

	http.HandleFunc("/api/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "only support GET method", http.StatusForbidden)
			return
		}

		bytes, _ := json.Marshal([]string{"/api/list", "/api/health", "/api/v1/test", "/api/v1/list", "/api/v1/sync"})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(bytes)

	})

	http.HandleFunc("/api/v1/test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "only support POST method", http.StatusForbidden)
			return
		}

		// parse post data
		data := new(TestRequest)
		if err := data.Bind(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := data.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := connectTest(data); err != nil {
			log.Errorf("connect test failed: %v", err)
			http.Error(w, fmt.Sprintf(`{"status":"failed", "msg": "%s"}`, err.Error()), http.StatusBadRequest)
			log.Println("POST /api/v1/test 400")
			return
		}

		bytes, _ := json.Marshal(map[string]string{"status": "ok", "msg": ""})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(bytes)

		log.Println("POST /api/v1/test 200")
	})

	http.HandleFunc("/api/v1/registry/test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "only support POST method", http.StatusForbidden)
			return
		}

		// parse post data
		data := new(TestRegistryRequest)
		if err := data.Bind(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := registryLoginTest(data); err != nil {
			log.Errorf("registry login test failed: %v", err)
			http.Error(w, fmt.Sprintf(`{"status":"failed", "msg": "%s"}`, err.Error()), http.StatusUnauthorized)
			log.Println("POST /api/v1/registry/test 401")
			return
		}

		bytes, _ := json.Marshal(map[string]string{"status": "ok", "msg": ""})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(bytes)

		log.Println("POST /api/v1/registry/test 200")
	})

	http.HandleFunc("/api/v1/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "only support POST method", http.StatusForbidden)
			return
		}

		// parse post data
		data := new(ListRequest)
		if err := data.Bind(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := data.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// list files
		//var files []string
		files := map[string]time.Time{}
		walkFun := func(path string, time time.Time) error {
			//files = append(files, file)
			files[path] = time
			return nil
		}

		cfg := &serverConfig{
			IP:       data.ServerIP,
			Port:     data.ServerPort,
			User:     data.Username,
			Password: data.Userpwd,
		}

		if err := Walk(cfg, data.SyncDirectory, walkFun); err != nil {
			log.Errorf("list files error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		md5 := map[string]string{}
		sha256 := map[string]string{}
		paths := map[string]string{}
		times := map[string]time.Time{}
		for file, time := range files {
			if strings.HasSuffix(file, ".md5") {
				content, err := readFile(cfg, file)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				last := strings.Split(file, "/")
				md5[strings.TrimSuffix(last[len(last)-1], ".md5")] = content
				paths[strings.TrimSuffix(last[len(last)-1], ".md5")] = filepath.Dir(file)
				times[strings.TrimSuffix(last[len(last)-1], ".md5")] = time
			}
			if strings.HasSuffix(file, ".sha256") {
				content, err := readFile(cfg, file)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				last := strings.Split(file, "/")
				sha256[strings.TrimSuffix(last[len(last)-1], ".sha256")] = content
			}
		}

		var out []*ListResponse
		for k, v := range md5 {
			parts := strings.Split(k, "#")
			tag := parts[len(parts)-1]
			r := &ListResponse{
				ImageFileDirectory: paths[k],
				ImageName:          strings.TrimSuffix(k, "#"+tag),
				ImageTag:           tag,
				ImageMD5Code:       v,
				ImageSha256Code:    sha256[k],
				DataTime:           times[k],
			}
			out = append(out, r)
		}

		bytes, err := json.Marshal(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(bytes)
	})

	http.HandleFunc("/api/v1/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "only support POST method", http.StatusForbidden)
			return
		}

		// parse post data
		data := new(SyncData)
		if err := data.Bind(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := data.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var out []*SyncResponse
		var wg sync.WaitGroup
		wg.Add(len(data.ImageItems))
		for _, image := range data.ImageItems {
			go func(image *ImageItem) {
				defer wg.Done()

				log.Println("download image", image.ImageFileName)
				path, err := downloadImage(data.ImageSource, image)
				if err != nil {
					log.Errorf("download image %s from ftp %v", image.ImageFileName, err)

					out = append(out, &SyncResponse{
						ImageName:       image.ImageName,
						ImageTag:        image.ImageTag,
						ImageSha256Code: image.ImageSha256Code,
						SyncResult:      "failed",
						Errmsg:          "download image error:" + err.Error(),
					})

					return
				}

				log.Println("check md5")
				if !md5Check(image.ImageMD5Code, path) {
					log.Errorf("md5 check failed for image %s", image.ImageFileName)
					out = append(out, &SyncResponse{
						ImageName:       image.ImageName,
						ImageTag:        image.ImageTag,
						ImageSha256Code: image.ImageSha256Code,
						SyncResult:      "failed",
						Errmsg:          "md5 mismatch",
					})

					return
				}

				log.Println("load image", image.ImageFileName)
				src, err := loadImage(path)
				if err != nil {
					log.Errorf("load image %s error: %v", image.ImageFileName, err)

					out = append(out, &SyncResponse{
						ImageName:       image.ImageName,
						ImageTag:        image.ImageTag,
						ImageSha256Code: image.ImageSha256Code,
						SyncResult:      "failed",
						Errmsg:          "load image error:" + err.Error(),
					})
					return
				}

				log.Println("tag image")
				im, err := tagImage(src, data.DestImageRepo, image.ImageName, image.ImageTag)
				if err != nil {
					log.Errorf("tag image %s error: %v", im, err)

					out = append(out, &SyncResponse{
						ImageName:       image.ImageName,
						ImageTag:        image.ImageTag,
						ImageSha256Code: image.ImageSha256Code,
						SyncResult:      "failed",
						Errmsg:          "tag image error:" + err.Error(),
					})

					return
				}

				log.Println("push image")
				if err := pushImage(data.DestImageRepoUsername, data.DestImageRepoToken, im); err != nil {
					log.Errorf("push image %s error: %v", path, err)

					out = append(out, &SyncResponse{
						ImageName:       image.ImageName,
						ImageTag:        image.ImageTag,
						ImageSha256Code: image.ImageSha256Code,
						SyncResult:      "failed",
						Errmsg:          "push image error:" + err.Error(),
					})

					return
				}

				out = append(out, &SyncResponse{
					ImageName:       image.ImageName,
					ImageTag:        image.ImageTag,
					ImageSha256Code: image.ImageSha256Code,
					SyncResult:      "succeed",
					Errmsg:          "",
				})
			}(image)
		}

		wg.Wait()

		bytes, err := json.Marshal(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(bytes)
	})

	log.Println("ftptool serve on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Errorf("listen error: %s", err)
	}
}
