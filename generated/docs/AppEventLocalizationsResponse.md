# AppEventLocalizationsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppEventLocalization**](AppEventLocalization.md) |  | 
**Included** | Pointer to [**[]AppEventLocalizationsResponseIncludedInner**](AppEventLocalizationsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppEventLocalizationsResponse

`func NewAppEventLocalizationsResponse(data []AppEventLocalization, links PagedDocumentLinks, ) *AppEventLocalizationsResponse`

NewAppEventLocalizationsResponse instantiates a new AppEventLocalizationsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventLocalizationsResponseWithDefaults

`func NewAppEventLocalizationsResponseWithDefaults() *AppEventLocalizationsResponse`

NewAppEventLocalizationsResponseWithDefaults instantiates a new AppEventLocalizationsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppEventLocalizationsResponse) GetData() []AppEventLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppEventLocalizationsResponse) GetDataOk() (*[]AppEventLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppEventLocalizationsResponse) SetData(v []AppEventLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppEventLocalizationsResponse) GetIncluded() []AppEventLocalizationsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppEventLocalizationsResponse) GetIncludedOk() (*[]AppEventLocalizationsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppEventLocalizationsResponse) SetIncluded(v []AppEventLocalizationsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppEventLocalizationsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventLocalizationsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventLocalizationsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventLocalizationsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppEventLocalizationsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppEventLocalizationsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppEventLocalizationsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppEventLocalizationsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


