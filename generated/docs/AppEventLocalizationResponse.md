# AppEventLocalizationResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppEventLocalization**](AppEventLocalization.md) |  | 
**Included** | Pointer to [**[]AppEventLocalizationsResponseIncludedInner**](AppEventLocalizationsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppEventLocalizationResponse

`func NewAppEventLocalizationResponse(data AppEventLocalization, links DocumentLinks, ) *AppEventLocalizationResponse`

NewAppEventLocalizationResponse instantiates a new AppEventLocalizationResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventLocalizationResponseWithDefaults

`func NewAppEventLocalizationResponseWithDefaults() *AppEventLocalizationResponse`

NewAppEventLocalizationResponseWithDefaults instantiates a new AppEventLocalizationResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppEventLocalizationResponse) GetData() AppEventLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppEventLocalizationResponse) GetDataOk() (*AppEventLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppEventLocalizationResponse) SetData(v AppEventLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppEventLocalizationResponse) GetIncluded() []AppEventLocalizationsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppEventLocalizationResponse) GetIncludedOk() (*[]AppEventLocalizationsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppEventLocalizationResponse) SetIncluded(v []AppEventLocalizationsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppEventLocalizationResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventLocalizationResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventLocalizationResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventLocalizationResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


