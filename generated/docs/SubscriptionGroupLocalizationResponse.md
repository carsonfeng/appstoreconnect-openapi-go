# SubscriptionGroupLocalizationResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionGroupLocalization**](SubscriptionGroupLocalization.md) |  | 
**Included** | Pointer to [**[]SubscriptionGroup**](SubscriptionGroup.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionGroupLocalizationResponse

`func NewSubscriptionGroupLocalizationResponse(data SubscriptionGroupLocalization, links DocumentLinks, ) *SubscriptionGroupLocalizationResponse`

NewSubscriptionGroupLocalizationResponse instantiates a new SubscriptionGroupLocalizationResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionGroupLocalizationResponseWithDefaults

`func NewSubscriptionGroupLocalizationResponseWithDefaults() *SubscriptionGroupLocalizationResponse`

NewSubscriptionGroupLocalizationResponseWithDefaults instantiates a new SubscriptionGroupLocalizationResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionGroupLocalizationResponse) GetData() SubscriptionGroupLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionGroupLocalizationResponse) GetDataOk() (*SubscriptionGroupLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionGroupLocalizationResponse) SetData(v SubscriptionGroupLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionGroupLocalizationResponse) GetIncluded() []SubscriptionGroup`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionGroupLocalizationResponse) GetIncludedOk() (*[]SubscriptionGroup, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionGroupLocalizationResponse) SetIncluded(v []SubscriptionGroup)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionGroupLocalizationResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionGroupLocalizationResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionGroupLocalizationResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionGroupLocalizationResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


