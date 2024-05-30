package jwt

type TokenPart struct {
	Header struct {
		PartName   string
		Attributes map[string]interface{}
	}
	Payload struct {
		PartName   string
		Attributes map[string]interface{}
	}
	Signature struct {
		PartName   string
		Attributes map[string]interface{}
	}
}

func CreateTokenPart(header map[string]interface{}, payload map[string]interface{}, signature map[string]interface{}) TokenPart {
	return TokenPart{
		Header: struct {
			PartName   string
			Attributes map[string]interface{}
		}{
			PartName:   "Header",
			Attributes: header,
		},
		Payload: struct {
			PartName   string
			Attributes map[string]interface{}
		}{
			PartName:   "Payload",
			Attributes: payload,
		},
		Signature: struct {
			PartName   string
			Attributes map[string]interface{}
		}{
			PartName:   "Signature",
			Attributes: signature,
		},
	}
}
