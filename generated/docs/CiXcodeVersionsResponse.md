# CiXcodeVersionsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]CiXcodeVersion**](CiXcodeVersion.md) |  | 
**Included** | Pointer to [**[]CiMacOsVersion**](CiMacOsVersion.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewCiXcodeVersionsResponse

`func NewCiXcodeVersionsResponse(data []CiXcodeVersion, links PagedDocumentLinks, ) *CiXcodeVersionsResponse`

NewCiXcodeVersionsResponse instantiates a new CiXcodeVersionsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiXcodeVersionsResponseWithDefaults

`func NewCiXcodeVersionsResponseWithDefaults() *CiXcodeVersionsResponse`

NewCiXcodeVersionsResponseWithDefaults instantiates a new CiXcodeVersionsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiXcodeVersionsResponse) GetData() []CiXcodeVersion`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiXcodeVersionsResponse) GetDataOk() (*[]CiXcodeVersion, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiXcodeVersionsResponse) SetData(v []CiXcodeVersion)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiXcodeVersionsResponse) GetIncluded() []CiMacOsVersion`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiXcodeVersionsResponse) GetIncludedOk() (*[]CiMacOsVersion, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiXcodeVersionsResponse) SetIncluded(v []CiMacOsVersion)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiXcodeVersionsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiXcodeVersionsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiXcodeVersionsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiXcodeVersionsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *CiXcodeVersionsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *CiXcodeVersionsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *CiXcodeVersionsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *CiXcodeVersionsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


