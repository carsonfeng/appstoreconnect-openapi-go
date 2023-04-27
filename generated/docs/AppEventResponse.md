# AppEventResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppEvent**](AppEvent.md) |  | 
**Included** | Pointer to [**[]AppEventLocalization**](AppEventLocalization.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppEventResponse

`func NewAppEventResponse(data AppEvent, links DocumentLinks, ) *AppEventResponse`

NewAppEventResponse instantiates a new AppEventResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventResponseWithDefaults

`func NewAppEventResponseWithDefaults() *AppEventResponse`

NewAppEventResponseWithDefaults instantiates a new AppEventResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppEventResponse) GetData() AppEvent`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppEventResponse) GetDataOk() (*AppEvent, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppEventResponse) SetData(v AppEvent)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppEventResponse) GetIncluded() []AppEventLocalization`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppEventResponse) GetIncludedOk() (*[]AppEventLocalization, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppEventResponse) SetIncluded(v []AppEventLocalization)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppEventResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


