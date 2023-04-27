# ProfileRelationshipsCertificates

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Links** | Pointer to [**AppAvailabilityRelationshipsAppLinks**](AppAvailabilityRelationshipsAppLinks.md) |  | [optional] 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 
**Data** | Pointer to [**[]ProfileRelationshipsCertificatesDataInner**](ProfileRelationshipsCertificatesDataInner.md) |  | [optional] 

## Methods

### NewProfileRelationshipsCertificates

`func NewProfileRelationshipsCertificates() *ProfileRelationshipsCertificates`

NewProfileRelationshipsCertificates instantiates a new ProfileRelationshipsCertificates object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewProfileRelationshipsCertificatesWithDefaults

`func NewProfileRelationshipsCertificatesWithDefaults() *ProfileRelationshipsCertificates`

NewProfileRelationshipsCertificatesWithDefaults instantiates a new ProfileRelationshipsCertificates object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLinks

`func (o *ProfileRelationshipsCertificates) GetLinks() AppAvailabilityRelationshipsAppLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ProfileRelationshipsCertificates) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ProfileRelationshipsCertificates) SetLinks(v AppAvailabilityRelationshipsAppLinks)`

SetLinks sets Links field to given value.

### HasLinks

`func (o *ProfileRelationshipsCertificates) HasLinks() bool`

HasLinks returns a boolean if a field has been set.

### GetMeta

`func (o *ProfileRelationshipsCertificates) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *ProfileRelationshipsCertificates) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *ProfileRelationshipsCertificates) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *ProfileRelationshipsCertificates) HasMeta() bool`

HasMeta returns a boolean if a field has been set.

### GetData

`func (o *ProfileRelationshipsCertificates) GetData() []ProfileRelationshipsCertificatesDataInner`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ProfileRelationshipsCertificates) GetDataOk() (*[]ProfileRelationshipsCertificatesDataInner, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ProfileRelationshipsCertificates) SetData(v []ProfileRelationshipsCertificatesDataInner)`

SetData sets Data field to given value.

### HasData

`func (o *ProfileRelationshipsCertificates) HasData() bool`

HasData returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


