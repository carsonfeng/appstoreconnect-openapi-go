# BuildBundleFileSizesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]BuildBundleFileSize**](BuildBundleFileSize.md) |  | 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewBuildBundleFileSizesResponse

`func NewBuildBundleFileSizesResponse(data []BuildBundleFileSize, links PagedDocumentLinks, ) *BuildBundleFileSizesResponse`

NewBuildBundleFileSizesResponse instantiates a new BuildBundleFileSizesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBuildBundleFileSizesResponseWithDefaults

`func NewBuildBundleFileSizesResponseWithDefaults() *BuildBundleFileSizesResponse`

NewBuildBundleFileSizesResponseWithDefaults instantiates a new BuildBundleFileSizesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *BuildBundleFileSizesResponse) GetData() []BuildBundleFileSize`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *BuildBundleFileSizesResponse) GetDataOk() (*[]BuildBundleFileSize, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *BuildBundleFileSizesResponse) SetData(v []BuildBundleFileSize)`

SetData sets Data field to given value.


### GetLinks

`func (o *BuildBundleFileSizesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *BuildBundleFileSizesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *BuildBundleFileSizesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *BuildBundleFileSizesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *BuildBundleFileSizesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *BuildBundleFileSizesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *BuildBundleFileSizesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


