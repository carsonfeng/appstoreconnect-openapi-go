/*
 * App Store Connect API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.2
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package appstoreopenapi

// BetaTestersResponse struct for BetaTestersResponse
type BetaTestersResponse struct {
	Data     []BetaTester       `json:"data"`
	Included []interface{}      `json:"included,omitempty"`
	Links    PagedDocumentLinks `json:"links"`
	Meta     PagingInformation  `json:"meta,omitempty"`
}