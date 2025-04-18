// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"k8c.io/dashboard/v2/pkg/test/e2e/utils/apiclient/models"
)

// PatchCurrentUserReadAnnouncementsReader is a Reader for the PatchCurrentUserReadAnnouncements structure.
type PatchCurrentUserReadAnnouncementsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchCurrentUserReadAnnouncementsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPatchCurrentUserReadAnnouncementsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewPatchCurrentUserReadAnnouncementsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewPatchCurrentUserReadAnnouncementsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPatchCurrentUserReadAnnouncementsOK creates a PatchCurrentUserReadAnnouncementsOK with default headers values
func NewPatchCurrentUserReadAnnouncementsOK() *PatchCurrentUserReadAnnouncementsOK {
	return &PatchCurrentUserReadAnnouncementsOK{}
}

/*
PatchCurrentUserReadAnnouncementsOK describes a response with status code 200, with default header values.

User
*/
type PatchCurrentUserReadAnnouncementsOK struct {
	Payload *models.User
}

// IsSuccess returns true when this patch current user read announcements o k response has a 2xx status code
func (o *PatchCurrentUserReadAnnouncementsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this patch current user read announcements o k response has a 3xx status code
func (o *PatchCurrentUserReadAnnouncementsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch current user read announcements o k response has a 4xx status code
func (o *PatchCurrentUserReadAnnouncementsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch current user read announcements o k response has a 5xx status code
func (o *PatchCurrentUserReadAnnouncementsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this patch current user read announcements o k response a status code equal to that given
func (o *PatchCurrentUserReadAnnouncementsOK) IsCode(code int) bool {
	return code == 200
}

func (o *PatchCurrentUserReadAnnouncementsOK) Error() string {
	return fmt.Sprintf("[PATCH /api/v1/me/readannouncements][%d] patchCurrentUserReadAnnouncementsOK  %+v", 200, o.Payload)
}

func (o *PatchCurrentUserReadAnnouncementsOK) String() string {
	return fmt.Sprintf("[PATCH /api/v1/me/readannouncements][%d] patchCurrentUserReadAnnouncementsOK  %+v", 200, o.Payload)
}

func (o *PatchCurrentUserReadAnnouncementsOK) GetPayload() *models.User {
	return o.Payload
}

func (o *PatchCurrentUserReadAnnouncementsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.User)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchCurrentUserReadAnnouncementsUnauthorized creates a PatchCurrentUserReadAnnouncementsUnauthorized with default headers values
func NewPatchCurrentUserReadAnnouncementsUnauthorized() *PatchCurrentUserReadAnnouncementsUnauthorized {
	return &PatchCurrentUserReadAnnouncementsUnauthorized{}
}

/*
PatchCurrentUserReadAnnouncementsUnauthorized describes a response with status code 401, with default header values.

EmptyResponse is a empty response
*/
type PatchCurrentUserReadAnnouncementsUnauthorized struct {
}

// IsSuccess returns true when this patch current user read announcements unauthorized response has a 2xx status code
func (o *PatchCurrentUserReadAnnouncementsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch current user read announcements unauthorized response has a 3xx status code
func (o *PatchCurrentUserReadAnnouncementsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch current user read announcements unauthorized response has a 4xx status code
func (o *PatchCurrentUserReadAnnouncementsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch current user read announcements unauthorized response has a 5xx status code
func (o *PatchCurrentUserReadAnnouncementsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this patch current user read announcements unauthorized response a status code equal to that given
func (o *PatchCurrentUserReadAnnouncementsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *PatchCurrentUserReadAnnouncementsUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /api/v1/me/readannouncements][%d] patchCurrentUserReadAnnouncementsUnauthorized ", 401)
}

func (o *PatchCurrentUserReadAnnouncementsUnauthorized) String() string {
	return fmt.Sprintf("[PATCH /api/v1/me/readannouncements][%d] patchCurrentUserReadAnnouncementsUnauthorized ", 401)
}

func (o *PatchCurrentUserReadAnnouncementsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPatchCurrentUserReadAnnouncementsDefault creates a PatchCurrentUserReadAnnouncementsDefault with default headers values
func NewPatchCurrentUserReadAnnouncementsDefault(code int) *PatchCurrentUserReadAnnouncementsDefault {
	return &PatchCurrentUserReadAnnouncementsDefault{
		_statusCode: code,
	}
}

/*
PatchCurrentUserReadAnnouncementsDefault describes a response with status code -1, with default header values.

errorResponse
*/
type PatchCurrentUserReadAnnouncementsDefault struct {
	_statusCode int

	Payload *models.ErrorResponse
}

// Code gets the status code for the patch current user read announcements default response
func (o *PatchCurrentUserReadAnnouncementsDefault) Code() int {
	return o._statusCode
}

// IsSuccess returns true when this patch current user read announcements default response has a 2xx status code
func (o *PatchCurrentUserReadAnnouncementsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this patch current user read announcements default response has a 3xx status code
func (o *PatchCurrentUserReadAnnouncementsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this patch current user read announcements default response has a 4xx status code
func (o *PatchCurrentUserReadAnnouncementsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this patch current user read announcements default response has a 5xx status code
func (o *PatchCurrentUserReadAnnouncementsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this patch current user read announcements default response a status code equal to that given
func (o *PatchCurrentUserReadAnnouncementsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

func (o *PatchCurrentUserReadAnnouncementsDefault) Error() string {
	return fmt.Sprintf("[PATCH /api/v1/me/readannouncements][%d] patchCurrentUserReadAnnouncements default  %+v", o._statusCode, o.Payload)
}

func (o *PatchCurrentUserReadAnnouncementsDefault) String() string {
	return fmt.Sprintf("[PATCH /api/v1/me/readannouncements][%d] patchCurrentUserReadAnnouncements default  %+v", o._statusCode, o.Payload)
}

func (o *PatchCurrentUserReadAnnouncementsDefault) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *PatchCurrentUserReadAnnouncementsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
