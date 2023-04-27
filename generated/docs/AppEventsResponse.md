# AppEventsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppEvent**](AppEvent.md) |  | 
**Included** | Pointer to [**[]AppEventLocalization**](AppEventLocalization.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppEventsResponse

`func NewAppEventsResponse(data []AppEvent, links PagedDocumentLinks, ) *AppEventsResponse`

NewAppEventsResponse instantiates a new AppEventsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventsResponseWithDefaults

`func NewAppEventsResponseWithDefaults() *AppEventsResponse`

NewAppEventsResponseWithDefaults instantiates a new AppEventsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppEventsResponse) GetData() []AppEvent`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppEventsResponse) GetDataOk() (*[]AppEvent, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppEventsResponse) SetData(v []AppEvent)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppEventsResponse) GetIncluded() []AppEventLocalization`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppEventsResponse) GetIncludedOk() (*[]AppEventLocalization, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppEventsResponse) SetIncluded(v []AppEventLocalization)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppEventsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppEventsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppEventsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppEventsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppEventsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


