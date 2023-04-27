# SubscriptionLocalizationResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionLocalization**](SubscriptionLocalization.md) |  | 
**Included** | Pointer to [**[]Subscription**](Subscription.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionLocalizationResponse

`func NewSubscriptionLocalizationResponse(data SubscriptionLocalization, links DocumentLinks, ) *SubscriptionLocalizationResponse`

NewSubscriptionLocalizationResponse instantiates a new SubscriptionLocalizationResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionLocalizationResponseWithDefaults

`func NewSubscriptionLocalizationResponseWithDefaults() *SubscriptionLocalizationResponse`

NewSubscriptionLocalizationResponseWithDefaults instantiates a new SubscriptionLocalizationResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionLocalizationResponse) GetData() SubscriptionLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionLocalizationResponse) GetDataOk() (*SubscriptionLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionLocalizationResponse) SetData(v SubscriptionLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionLocalizationResponse) GetIncluded() []Subscription`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionLocalizationResponse) GetIncludedOk() (*[]Subscription, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionLocalizationResponse) SetIncluded(v []Subscription)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionLocalizationResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionLocalizationResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionLocalizationResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionLocalizationResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


