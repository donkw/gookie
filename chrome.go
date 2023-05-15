package gookie

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/user"

	"github.com/donkw/gookie/cryption"
	_ "github.com/mattn/go-sqlite3"
)

type chrome struct {
	config *Config
}

type Config struct {
	UserDataPath       string
	LocalStateFilePath string
	CookieFilePath     string
	AESGCMKey          []byte
	Version            string
}

// NewChrome returns a new chrome struct
func NewChrome() (*chrome, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}
	config := &Config{}
	config.UserDataPath = currentUser.HomeDir + `\AppData\Local\Google\Chrome\User Data`
	config.LocalStateFilePath = config.UserDataPath + `\Local State`
	config.CookieFilePath = config.UserDataPath + `\Default\Network\Cookies`
	return NewChromeWith(config)
}
func NewChromeWith(cf *Config) (*chrome, error) {
	c := &chrome{config: cf}
	if err := c.setAESGCMKey(); err != nil {
		return nil, err
	}
	return c, nil
}

// SetAESGCMKey sets the AESGCMKey of chrome.
func (c *chrome) setAESGCMKey() error {
	localStateFile, err := os.ReadFile(c.config.LocalStateFilePath)
	if err != nil {
		return err
	}
	localState := make(map[string]interface{})
	if err = json.Unmarshal(localStateFile, &localState); err != nil {
		return err
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string))
	if err != nil {
		return err
	}
	var decryptedKey []byte
	if bytes.Equal(encryptedKey[:5], []byte{'D', 'P', 'A', 'P', 'I'}) {
		decryptedKey, err = cryption.Decrypt(encryptedKey[5:])
	} else {
		decryptedKey, err = cryption.Decrypt(encryptedKey)
	}
	if err != nil {
		return err
	}
	c.config.AESGCMKey = decryptedKey
	return nil
}

// GetCookies get cookies map that decrypted
func (c *chrome) GetCookies(hostKey string) ([]Cookie, error) {
	cookieDb, err := sql.Open("sqlite3", c.config.CookieFilePath)
	if err != nil {
		return nil, err
	}
	defer cookieDb.Close()
	rows, err := cookieDb.Query("SELECT name, encrypted_value FROM cookies WHERE host_key = ?", hostKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cookies []Cookie
	for rows.Next() {
		var name string
		var encryptedData []byte
		if err = rows.Scan(&name, &encryptedData); err != nil {
			return nil, err
		}
		var decryptedData []byte
		prefix := encryptedData[:3]
		if bytes.Equal(prefix, []byte{'v', '1', '0'}) || bytes.Equal(prefix, []byte{'v', '1', '1'}) {
			decryptedData, err = cryption.DecryptWithAESGCM(c.config.AESGCMKey, encryptedData[3:15], encryptedData[15:])
			if err != nil {
				return nil, err
			}
		} else {
			decryptedData, err = cryption.Decrypt(encryptedData)
			if err != nil {
				return nil, err
			}
		}
		cookies = append(cookies, Cookie{
			Key:   name,
			Value: string(decryptedData),
		})
	}
	return cookies, nil
}
