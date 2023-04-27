# AppClipDefaultExperiencesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppClipDefaultExperience**](AppClipDefaultExperience.md) |  | 
**Included** | Pointer to [**[]AppClipDefaultExperiencesResponseIncludedInner**](AppClipDefaultExperiencesResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppClipDefaultExperiencesResponse

`func NewAppClipDefaultExperiencesResponse(data []AppClipDefaultExperience, links PagedDocumentLinks, ) *AppClipDefaultExperiencesResponse`

NewAppClipDefaultExperiencesResponse instantiates a new AppClipDefaultExperiencesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipDefaultExperiencesResponseWithDefaults

`func NewAppClipDefaultExperiencesResponseWithDefaults() *AppClipDefaultExperiencesResponse`

NewAppClipDefaultExperiencesResponseWithDefaults instantiates a new AppClipDefaultExperiencesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipDefaultExperiencesResponse) GetData() []AppClipDefaultExperience`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipDefaultExperiencesResponse) GetDataOk() (*[]AppClipDefaultExperience, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipDefaultExperiencesResponse) SetData(v []AppClipDefaultExperience)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipDefaultExperiencesResponse) GetIncluded() []AppClipDefaultExperiencesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipDefaultExperiencesResponse) GetIncludedOk() (*[]AppClipDefaultExperiencesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipDefaultExperiencesResponse) SetIncluded(v []AppClipDefaultExperiencesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipDefaultExperiencesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipDefaultExperiencesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipDefaultExperiencesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipDefaultExperiencesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppClipDefaultExperiencesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppClipDefaultExperiencesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppClipDefaultExperiencesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppClipDefaultExperiencesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


