package models

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

type StructValidator struct {
	Validator *validator.Validate
}

func (v *StructValidator) Validate(out any) error {
	err := v.Validator.Struct(out)
	if err != nil {
		reflected := reflect.TypeOf(out)
		if reflected.Kind() == reflect.Ptr {
			reflected = reflected.Elem()
		}
		for _, err := range err.(validator.ValidationErrors) {
			field, _ := reflected.FieldByName(err.StructField())
			jsonTag := field.Tag.Get("json")
			validateTag := field.Tag.Get("validate")

			var options []string
			if strings.Contains(validateTag, "oneof=") {
				options = strings.Split(validateTag, "oneof=")
			}
			fmt.Println(options)

			switch err.Tag() {
			case "required":
				return fmt.Errorf("missing field: %s", jsonTag)
			case "email":
				return fmt.Errorf("invalid email format")
			case "gte", "lte":
				return fmt.Errorf("invalid value for field: %s", jsonTag)
			case "min":
				return fmt.Errorf("%s must be at least %s characters long", jsonTag, err.Param())
			case "oneof":
				return fmt.Errorf("invalid value for field: %s, options are: %s", jsonTag, options[1])
			default:
				return fmt.Errorf("invalid input: %s", jsonTag)
			}
		}
	}
	return nil
}
