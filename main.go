package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/ssh"
)

type PathMapping struct {
	Method string `db:"method"`
	Path   string `db:"path"`
}

type ConfigPath struct {
	TokenType         string `db:"token_type"`
	TokenValue        string `db:"token_value"`
	SshAuthorizeType  string `db:"ssh_authorize_type"`
	SshAuthorizeValue string `db:"ssh_authorize_value"`
	SshHost           string `db:"ssh_host"`
	SshPort           string `db:"ssh_port"`
	SshUser           string `db:"ssh_user"`
	SshCommand        string `db:"ssh_command"`
}

func main() {
	e := echo.New()

	DB_HOST := os.Getenv("DB_HOST")
	DB_USER := os.Getenv("DB_USER")
	DB_PASS := os.Getenv("DB_PASS")
	DB_NAME := os.Getenv("DB_NAME")

	db, err := sqlx.Open(
		"mysql",
		fmt.Sprintf("%s:%s!@tcp(%s)/%s", DB_USER, DB_PASS, DB_HOST, DB_NAME),
	)
	if err != nil {
		panic(err)
	}

	pathMappings := []PathMapping{}
	query := `SELECT method, path FROM path_mapping`
	err = db.Select(&pathMappings, query)
	if err != nil {
		panic(err)
	}

	for _, pathMapping := range pathMappings {
		e.Add(pathMapping.Method, pathMapping.Path, func(c echo.Context) error {
			config := ConfigPath{}
			query := `SELECT
				token_type, token_value, ssh_authorize_type,
				ssh_authorize_value, ssh_host, ssh_port, ssh_user, ssh_command
				FROM path_mapping WHERE path=? AND method=?`
			err = db.Get(&config, query, pathMapping.Path, pathMapping.Method)
			if err != nil {
				panic(err)
			}

			checkAuth := checkAuthorization(c, config)
			if checkAuth != nil {
				return checkAuth
			}

			if config.SshAuthorizeType == "private_key" {
				return getResponseNotImplement(c)
			} else {
				sshConfig := &ssh.ClientConfig{
					User:            config.SshUser,
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Auth: []ssh.AuthMethod{
						ssh.Password(config.SshAuthorizeValue),
					},
				}
				client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", config.SshHost, config.SshPort), sshConfig)
				if client != nil {
					defer client.Close()
				}
				if err != nil {
					return getResponseSshFailed(c)
				}
				session, err := client.NewSession()
				if session != nil {
					defer session.Close()
				}
				if err != nil {
					return getResponseSshFailed(c)
				}

				var stdout, stderr bytes.Buffer
				session.Stdout = &stdout
				session.Stderr = &stderr
				err = session.Run(config.SshCommand)
				if err != nil {
					return getResponseFailedExecute(c)
				}

				if stderr.String() != "" {
					return getResponseSuccess(c, stderr.String())
				}

				return getResponseSuccess(c, stdout.String())
			}
		})
	}

	e.Logger.Fatal(e.Start(":8000"))
}

func checkAuthorization(c echo.Context, config ConfigPath) error {
	if config.TokenType != "open" {
		if config.TokenType == "bearer" {
			return getResponseNotImplement(c)
		} else if config.TokenType == "custom" {
			return getResponseNotImplement(c)
		} else {
			authorizationHeader := c.Request().Header["Authorization"][0]
			if authorizationHeader != config.TokenValue {
				return getResponseNotAuthorize(c)
			}
		}
	}
	return nil
}

type response struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func getResponseNotImplement(c echo.Context) error {
	return c.JSON(http.StatusOK, response{
		Status:  http.StatusNotImplemented,
		Message: "Not Implement",
	})
}

func getResponseNotAuthorize(c echo.Context) error {
	return c.JSON(http.StatusOK, response{
		Status:  http.StatusUnauthorized,
		Message: "Not Authorize",
	})
}

func getResponseSuccess(c echo.Context, message string) error {
	return c.JSON(http.StatusOK, response{
		Status:  http.StatusOK,
		Message: message,
	})
}

func getResponseSshFailed(c echo.Context) error {
	return c.JSON(http.StatusOK, response{
		Status:  http.StatusInternalServerError,
		Message: "Failed to remote server",
	})
}

func getResponseFailedExecute(c echo.Context) error {
	return c.JSON(http.StatusOK, response{
		Status:  http.StatusInternalServerError,
		Message: "Failed execute command",
	})
}
