/*
 * App Store Connect API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.2
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package appstoreopenapi

// AppPricePointResponse struct for AppPricePointResponse
type AppPricePointResponse struct {
	Data     AppPricePoint `json:"data"`
	Included []Territory   `json:"included,omitempty"`
	Links    DocumentLinks `json:"links"`
}