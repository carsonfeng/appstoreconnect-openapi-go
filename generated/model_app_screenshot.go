/*
 * App Store Connect API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.2
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package appstoreopenapi

// AppScreenshot struct for AppScreenshot
type AppScreenshot struct {
	Type          string                     `json:"type"`
	Id            string                     `json:"id"`
	Attributes    AppScreenshotAttributes    `json:"attributes,omitempty"`
	Relationships AppScreenshotRelationships `json:"relationships,omitempty"`
	Links         ResourceLinks              `json:"links"`
}