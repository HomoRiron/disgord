package disgord

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type ChangePswdRequest struct {
	OldPassword string `json:"password"`
	NewPassword string `json:"new_password"`
}
type UserProfile struct {
	ID            string      `json:"id"`
	Username      string      `json:"username"`
	Avatar        string      `json:"avatar"`
	Discriminator string      `json:"discriminator"`
	PublicFlags   int         `json:"public_flags"`
	Flags         int         `json:"flags"`
	Banner        interface{} `json:"banner"`
	BannerColor   interface{} `json:"banner_color"`
	AccentColor   interface{} `json:"accent_color"`
	Bio           string      `json:"bio"`
	Pronouns      string      `json:"pronouns"`
	Token         string      `json:"token"`
	Locale        string      `json:"locale"`
	NsfwAllowed   bool        `json:"nsfw_allowed"`
	MfaEnabled    bool        `json:"mfa_enabled"`
	Email         string      `json:"email"`
	Verified      bool        `json:"verified"`
	Phone         interface{} `json:"phone"`
}

func (d *discordClient) ChangePassword(old, new string) (*UserProfile, error) {
	changePswdReq := &ChangePswdRequest{
		OldPassword: old,
		NewPassword: new,
	}
	changePswdReqJson, _ := json.Marshal(changePswdReq)
	req, err := http.NewRequest(
		http.MethodPatch,
		meURL,
		bytes.NewBuffer(changePswdReqJson))
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0")
	req.Header.Add("Authorization", d.token)
	if err != nil {
		return nil, err
	}
	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	byteArray, _ := ioutil.ReadAll(resp.Body)
	jsonBytes := ([]byte)(byteArray)
	changePswdRes := &UserProfile{}
	err = json.Unmarshal(jsonBytes, changePswdRes)
	if err != nil {
		return nil, err
	}
	return changePswdRes, nil
}
