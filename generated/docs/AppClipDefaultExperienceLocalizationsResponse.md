# AppClipDefaultExperienceLocalizationsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppClipDefaultExperienceLocalization**](AppClipDefaultExperienceLocalization.md) |  | 
**Included** | Pointer to [**[]AppClipDefaultExperienceLocalizationsResponseIncludedInner**](AppClipDefaultExperienceLocalizationsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppClipDefaultExperienceLocalizationsResponse

`func NewAppClipDefaultExperienceLocalizationsResponse(data []AppClipDefaultExperienceLocalization, links PagedDocumentLinks, ) *AppClipDefaultExperienceLocalizationsResponse`

NewAppClipDefaultExperienceLocalizationsResponse instantiates a new AppClipDefaultExperienceLocalizationsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipDefaultExperienceLocalizationsResponseWithDefaults

`func NewAppClipDefaultExperienceLocalizationsResponseWithDefaults() *AppClipDefaultExperienceLocalizationsResponse`

NewAppClipDefaultExperienceLocalizationsResponseWithDefaults instantiates a new AppClipDefaultExperienceLocalizationsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipDefaultExperienceLocalizationsResponse) GetData() []AppClipDefaultExperienceLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipDefaultExperienceLocalizationsResponse) GetDataOk() (*[]AppClipDefaultExperienceLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipDefaultExperienceLocalizationsResponse) SetData(v []AppClipDefaultExperienceLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipDefaultExperienceLocalizationsResponse) GetIncluded() []AppClipDefaultExperienceLocalizationsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipDefaultExperienceLocalizationsResponse) GetIncludedOk() (*[]AppClipDefaultExperienceLocalizationsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipDefaultExperienceLocalizationsResponse) SetIncluded(v []AppClipDefaultExperienceLocalizationsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipDefaultExperienceLocalizationsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipDefaultExperienceLocalizationsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipDefaultExperienceLocalizationsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipDefaultExperienceLocalizationsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppClipDefaultExperienceLocalizationsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppClipDefaultExperienceLocalizationsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppClipDefaultExperienceLocalizationsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppClipDefaultExperienceLocalizationsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


