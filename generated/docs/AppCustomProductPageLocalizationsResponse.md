# AppCustomProductPageLocalizationsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppCustomProductPageLocalization**](AppCustomProductPageLocalization.md) |  | 
**Included** | Pointer to [**[]AppCustomProductPageLocalizationsResponseIncludedInner**](AppCustomProductPageLocalizationsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppCustomProductPageLocalizationsResponse

`func NewAppCustomProductPageLocalizationsResponse(data []AppCustomProductPageLocalization, links PagedDocumentLinks, ) *AppCustomProductPageLocalizationsResponse`

NewAppCustomProductPageLocalizationsResponse instantiates a new AppCustomProductPageLocalizationsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppCustomProductPageLocalizationsResponseWithDefaults

`func NewAppCustomProductPageLocalizationsResponseWithDefaults() *AppCustomProductPageLocalizationsResponse`

NewAppCustomProductPageLocalizationsResponseWithDefaults instantiates a new AppCustomProductPageLocalizationsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppCustomProductPageLocalizationsResponse) GetData() []AppCustomProductPageLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppCustomProductPageLocalizationsResponse) GetDataOk() (*[]AppCustomProductPageLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppCustomProductPageLocalizationsResponse) SetData(v []AppCustomProductPageLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppCustomProductPageLocalizationsResponse) GetIncluded() []AppCustomProductPageLocalizationsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppCustomProductPageLocalizationsResponse) GetIncludedOk() (*[]AppCustomProductPageLocalizationsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppCustomProductPageLocalizationsResponse) SetIncluded(v []AppCustomProductPageLocalizationsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppCustomProductPageLocalizationsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppCustomProductPageLocalizationsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppCustomProductPageLocalizationsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppCustomProductPageLocalizationsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppCustomProductPageLocalizationsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppCustomProductPageLocalizationsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppCustomProductPageLocalizationsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppCustomProductPageLocalizationsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


