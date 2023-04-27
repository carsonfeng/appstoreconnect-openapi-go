# AppStoreVersionExperimentsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppStoreVersionExperiment**](AppStoreVersionExperiment.md) |  | 
**Included** | Pointer to [**[]AppStoreVersionExperimentsResponseIncludedInner**](AppStoreVersionExperimentsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppStoreVersionExperimentsResponse

`func NewAppStoreVersionExperimentsResponse(data []AppStoreVersionExperiment, links PagedDocumentLinks, ) *AppStoreVersionExperimentsResponse`

NewAppStoreVersionExperimentsResponse instantiates a new AppStoreVersionExperimentsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionExperimentsResponseWithDefaults

`func NewAppStoreVersionExperimentsResponseWithDefaults() *AppStoreVersionExperimentsResponse`

NewAppStoreVersionExperimentsResponseWithDefaults instantiates a new AppStoreVersionExperimentsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppStoreVersionExperimentsResponse) GetData() []AppStoreVersionExperiment`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppStoreVersionExperimentsResponse) GetDataOk() (*[]AppStoreVersionExperiment, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppStoreVersionExperimentsResponse) SetData(v []AppStoreVersionExperiment)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppStoreVersionExperimentsResponse) GetIncluded() []AppStoreVersionExperimentsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppStoreVersionExperimentsResponse) GetIncludedOk() (*[]AppStoreVersionExperimentsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppStoreVersionExperimentsResponse) SetIncluded(v []AppStoreVersionExperimentsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppStoreVersionExperimentsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionExperimentsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionExperimentsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionExperimentsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppStoreVersionExperimentsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppStoreVersionExperimentsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppStoreVersionExperimentsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppStoreVersionExperimentsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


