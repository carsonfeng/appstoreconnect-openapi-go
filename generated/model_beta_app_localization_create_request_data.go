/*
 * App Store Connect API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.2
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package appstoreopenapi

// BetaAppLocalizationCreateRequestData struct for BetaAppLocalizationCreateRequestData
type BetaAppLocalizationCreateRequestData struct {
	Type          string                                         `json:"type"`
	Attributes    BetaAppLocalizationCreateRequestDataAttributes `json:"attributes"`
	Relationships AppPreOrderCreateRequestDataRelationships      `json:"relationships"`
}