# SubscriptionAppStoreReviewScreenshotResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionAppStoreReviewScreenshot**](SubscriptionAppStoreReviewScreenshot.md) |  | 
**Included** | Pointer to [**[]Subscription**](Subscription.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionAppStoreReviewScreenshotResponse

`func NewSubscriptionAppStoreReviewScreenshotResponse(data SubscriptionAppStoreReviewScreenshot, links DocumentLinks, ) *SubscriptionAppStoreReviewScreenshotResponse`

NewSubscriptionAppStoreReviewScreenshotResponse instantiates a new SubscriptionAppStoreReviewScreenshotResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionAppStoreReviewScreenshotResponseWithDefaults

`func NewSubscriptionAppStoreReviewScreenshotResponseWithDefaults() *SubscriptionAppStoreReviewScreenshotResponse`

NewSubscriptionAppStoreReviewScreenshotResponseWithDefaults instantiates a new SubscriptionAppStoreReviewScreenshotResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionAppStoreReviewScreenshotResponse) GetData() SubscriptionAppStoreReviewScreenshot`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionAppStoreReviewScreenshotResponse) GetDataOk() (*SubscriptionAppStoreReviewScreenshot, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionAppStoreReviewScreenshotResponse) SetData(v SubscriptionAppStoreReviewScreenshot)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionAppStoreReviewScreenshotResponse) GetIncluded() []Subscription`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionAppStoreReviewScreenshotResponse) GetIncludedOk() (*[]Subscription, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionAppStoreReviewScreenshotResponse) SetIncluded(v []Subscription)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionAppStoreReviewScreenshotResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionAppStoreReviewScreenshotResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionAppStoreReviewScreenshotResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionAppStoreReviewScreenshotResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


