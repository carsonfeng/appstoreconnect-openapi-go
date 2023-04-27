# AppCustomProductPageVersionsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppCustomProductPageVersion**](AppCustomProductPageVersion.md) |  | 
**Included** | Pointer to [**[]AppCustomProductPageVersionsResponseIncludedInner**](AppCustomProductPageVersionsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppCustomProductPageVersionsResponse

`func NewAppCustomProductPageVersionsResponse(data []AppCustomProductPageVersion, links PagedDocumentLinks, ) *AppCustomProductPageVersionsResponse`

NewAppCustomProductPageVersionsResponse instantiates a new AppCustomProductPageVersionsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppCustomProductPageVersionsResponseWithDefaults

`func NewAppCustomProductPageVersionsResponseWithDefaults() *AppCustomProductPageVersionsResponse`

NewAppCustomProductPageVersionsResponseWithDefaults instantiates a new AppCustomProductPageVersionsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppCustomProductPageVersionsResponse) GetData() []AppCustomProductPageVersion`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppCustomProductPageVersionsResponse) GetDataOk() (*[]AppCustomProductPageVersion, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppCustomProductPageVersionsResponse) SetData(v []AppCustomProductPageVersion)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppCustomProductPageVersionsResponse) GetIncluded() []AppCustomProductPageVersionsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppCustomProductPageVersionsResponse) GetIncludedOk() (*[]AppCustomProductPageVersionsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppCustomProductPageVersionsResponse) SetIncluded(v []AppCustomProductPageVersionsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppCustomProductPageVersionsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppCustomProductPageVersionsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppCustomProductPageVersionsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppCustomProductPageVersionsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppCustomProductPageVersionsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppCustomProductPageVersionsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppCustomProductPageVersionsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppCustomProductPageVersionsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


