/*
 * App Store Connect API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.2
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package appstoreopenapi

// CertificateType the model 'CertificateType'
type CertificateType string

// List of CertificateType
const (
	CERTIFICATETYPE_IOS_DEVELOPMENT            CertificateType = "IOS_DEVELOPMENT"
	CERTIFICATETYPE_IOS_DISTRIBUTION           CertificateType = "IOS_DISTRIBUTION"
	CERTIFICATETYPE_MAC_APP_DISTRIBUTION       CertificateType = "MAC_APP_DISTRIBUTION"
	CERTIFICATETYPE_MAC_INSTALLER_DISTRIBUTION CertificateType = "MAC_INSTALLER_DISTRIBUTION"
	CERTIFICATETYPE_MAC_APP_DEVELOPMENT        CertificateType = "MAC_APP_DEVELOPMENT"
	CERTIFICATETYPE_DEVELOPER_ID_KEXT          CertificateType = "DEVELOPER_ID_KEXT"
	CERTIFICATETYPE_DEVELOPER_ID_APPLICATION   CertificateType = "DEVELOPER_ID_APPLICATION"
	CERTIFICATETYPE_DEVELOPMENT                CertificateType = "DEVELOPMENT"
	CERTIFICATETYPE_DISTRIBUTION               CertificateType = "DISTRIBUTION"
)