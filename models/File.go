package models

type File struct {
	Password string `json:"password,omitempty" xml:"password,omitempty" form:"password,omitempty" query:"password,omitempty" redis:"password,omitempty"`
	PasswordProvided bool `redis:"provided,omitempty"`
	PasswordProvidedKey string `redis:"provided_key,omitempty"`
	Token []byte `redis:"token,omitempty"`
	TTL int `json:"ttl,omitempty" xml:"ttl,omitempty" form:"ttl,omitempty" query:"ttl,omitempty" redis:"ttl,omitempty"`
	Views int `json:"views,omitempty" xml:"views,omitempty" form:"views,omitempty" query:"views,omitempty" redis:"views,omitempty"`
	ViewsCount int `redis:"views_count,omitempty"`
	Deletable bool `json:"deletable,omitempty" xml:"deletable,omitempty" form:"deletable,omitempty" query:"deletable,omitempty" redis:"deletable,omitempty"`
	FileKey string `json:"file_key,omitempty" xml:"file_key,omitempty" form:"file_key,omitempty" query:"password_key,omitempty"`
	Link string `json:"link,omitempty" xml:"link,omitempty" form:"link,omitempty" query:"link,omitempty"`
	LinkApi string `json:"link_api,omitempty" xml:"link_api,omitempty" form:"link_api,omitempty" query:"link_api,omitempty"`
}
