# CiMacOsVersionsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]CiMacOsVersion**](CiMacOsVersion.md) |  | 
**Included** | Pointer to [**[]CiXcodeVersion**](CiXcodeVersion.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewCiMacOsVersionsResponse

`func NewCiMacOsVersionsResponse(data []CiMacOsVersion, links PagedDocumentLinks, ) *CiMacOsVersionsResponse`

NewCiMacOsVersionsResponse instantiates a new CiMacOsVersionsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiMacOsVersionsResponseWithDefaults

`func NewCiMacOsVersionsResponseWithDefaults() *CiMacOsVersionsResponse`

NewCiMacOsVersionsResponseWithDefaults instantiates a new CiMacOsVersionsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiMacOsVersionsResponse) GetData() []CiMacOsVersion`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiMacOsVersionsResponse) GetDataOk() (*[]CiMacOsVersion, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiMacOsVersionsResponse) SetData(v []CiMacOsVersion)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiMacOsVersionsResponse) GetIncluded() []CiXcodeVersion`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiMacOsVersionsResponse) GetIncludedOk() (*[]CiXcodeVersion, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiMacOsVersionsResponse) SetIncluded(v []CiXcodeVersion)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiMacOsVersionsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiMacOsVersionsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiMacOsVersionsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiMacOsVersionsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *CiMacOsVersionsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *CiMacOsVersionsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *CiMacOsVersionsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *CiMacOsVersionsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


