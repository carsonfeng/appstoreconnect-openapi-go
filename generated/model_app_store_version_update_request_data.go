/*
 * App Store Connect API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.2
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package appstoreopenapi

// AppStoreVersionUpdateRequestData struct for AppStoreVersionUpdateRequestData
type AppStoreVersionUpdateRequestData struct {
	Type          string                                        `json:"type"`
	Id            string                                        `json:"id"`
	Attributes    AppStoreVersionUpdateRequestDataAttributes    `json:"attributes,omitempty"`
	Relationships AppStoreVersionUpdateRequestDataRelationships `json:"relationships,omitempty"`
}