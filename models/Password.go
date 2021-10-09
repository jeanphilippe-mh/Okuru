package models

// Security to counter bots and scrappers.
type Password struct {
	Password    string `json:"password,omitempty" xml:"password,omitempty" form:"password,omitempty" query:"password,omitempty" redis:"password,omitempty"`
	Token       []byte `json:"token,omitempty" xml:"token,omitempty" form:"token,omitempty" query:"token,omitempty" redis:"token,omitempty"`
	TTL         int    `json:"ttl,omitempty" xml:"ttl,omitempty" form:"ttl,omitempty" query:"ttl,omitempty" redis:"ttl,omitempty"`
	Views       int    `json:"views,omitempty" xml:"views,omitempty" form:"views,omitempty" query:"views,omitempty" redis:"views,omitempty"`
	ViewsCount  int    `json:"views_count,omitempty" xml:"views_count,omitempty" form:"views_count,omitempty" query:"views_count,omitempty" redis:"views_count,omitempty"`
	Deletable   bool   `json:"deletable,omitempty" xml:"deletable,omitempty" form:"deletable,omitempty" query:"deletable,omitempty" redis:"deletable,omitempty"`
	PasswordKey string `json:"password_key,omitempty" xml:"password_key,omitempty" form:"password_key,omitempty" query:"password_key,omitempty"`
	Link        string `json:"link,omitempty" xml:"link,omitempty" form:"link,omitempty" query:"link,omitempty"`
	LinkApi     string `json:"link_api,omitempty" xml:"link_api,omitempty" form:"link_api,omitempty" query:"link_api,omitempty"`
}
