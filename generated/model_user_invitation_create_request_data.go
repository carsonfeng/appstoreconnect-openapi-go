/*
 * App Store Connect API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.2
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package appstoreopenapi

// UserInvitationCreateRequestData struct for UserInvitationCreateRequestData
type UserInvitationCreateRequestData struct {
	Type          string                                       `json:"type"`
	Attributes    UserInvitationCreateRequestDataAttributes    `json:"attributes"`
	Relationships UserInvitationCreateRequestDataRelationships `json:"relationships,omitempty"`
}