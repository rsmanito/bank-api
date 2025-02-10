package models

import (
	"fmt"
	"reflect"

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

			switch err.Tag() {
			case "required":
				return fmt.Errorf("missing field: %s", jsonTag)
			case "email":
				return fmt.Errorf("invalid email format")
			case "gte", "lte":
				return fmt.Errorf("invalid value for field: %s", jsonTag)
			case "min":
				return fmt.Errorf("%s must be at least %s characters long", jsonTag, err.Param())
			default:
				return fmt.Errorf("invalid input: %s", jsonTag)
			}
		}
	}
	return nil
}
