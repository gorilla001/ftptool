package main

import (
	"encoding/json"
	"io"
)

type SyncData struct {
	DestImageRepo         string       `json:"destImageRepo"`
	DestImageRepoToken    string       `json:"destImageRepoToken"`
	DestImageRepoUsername string       `json:"destImageRepoUsername"`
	ImageSource           *ImageSource `json:"imageSource"`
	ImageItems            []*ImageItem `json:"imageItems"`
}

type ImageSource struct {
	ImageSourceName string `json:"imageSourceName"`
	ImageSourceType string `json:"imageSourceType"`
	ServerIP        string `json:"serverIP"`
	ServerPort      int    `json:"serverPort"`
	SyncDirectory   string `json:"syncDirectory"`
	Username        string `json:"username"`
	Userpwd         string `json:"userpwd"`
}

type ImageItem struct {
	ImageFileDirectory string `json:"imageFileDirectory"`
	ImageFileName      string `json:"imageFileName"`
	ImageMD5Code       string `json:"imageMD5Code"`
	ImageName          string `json:"imageName"`
	ImageSha256Code    string `json:"imageSha256Code"`
	ImageTag           string `json:"imageTag"`
	OperationCount     int    `json:"operationCount"`
}

func (sd *SyncData) Bind(b io.ReadCloser) error {
	return json.NewDecoder(b).Decode(sd)
}

func (sd *SyncData) Validate() error {
	return nil
}

type serverConfig struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type ListRequest struct {
	ImageSourceName string `json:"imageSourceName"`
	ImageSourceType string `json:"imageSourceType"`
	ServerIP        string `json:"serverIP"`
	ServerPort      int    `json:"serverPort"`
	SyncDirectory   string `json:"syncDirectory"`
	Username        string `json:"username"`
	Userpwd         string `json:"userpwd"`
}

func (ld *ListRequest) Bind(b io.ReadCloser) error {
	return json.NewDecoder(b).Decode(ld)
}

func (ld *ListRequest) Validate() error {
	return nil
}

type ListResponse struct {
	ImageFileDirectory string `json:"imageFileDirectory"`
	ImageName          string `json:"imageName"`
	ImageTag           string `json:"imageTag"`
	ImageMD5Code       string `json:"imageMD5Code"`
	ImageSha256Code    string `json:"imageSha256Code"`
}

type TestRequest struct {
	ImageSourceName string `json:"imageSourceName"`
	ImageSourceType string `json:"imageSourceType"`
	ServerIP        string `json:"serverIP"`
	ServerPort      int    `json:"serverPort"`
	SyncDirectory   string `json:"syncDirectory"`
	Username        string `json:"username"`
	Userpwd         string `json:"userpwd"`
}

func (tr *TestRequest) Bind(b io.ReadCloser) error {
	return json.NewDecoder(b).Decode(tr)
}

func (tr *TestRequest) Validate() error {
	return nil
}

type SyncResponse struct {
	ImageName       string `json:"imageName"`
	ImageTag        string `json:"imageTag"`
	ImageSha256Code string `json:"imageSha256Code"`
	SyncResult      string `json:"syncResult"`
	Errmsg          string `json:"errmsg"`
}
