/*
 * App Store Connect API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.2
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package appstoreopenapi

// AppMediaAssetState struct for AppMediaAssetState
type AppMediaAssetState struct {
	Errors   []AppMediaStateError `json:"errors,omitempty"`
	Warnings []AppMediaStateError `json:"warnings,omitempty"`
	State    string               `json:"state,omitempty"`
}