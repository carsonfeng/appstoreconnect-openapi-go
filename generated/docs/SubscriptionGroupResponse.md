# SubscriptionGroupResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionGroup**](SubscriptionGroup.md) |  | 
**Included** | Pointer to [**[]SubscriptionGroupsResponseIncludedInner**](SubscriptionGroupsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionGroupResponse

`func NewSubscriptionGroupResponse(data SubscriptionGroup, links DocumentLinks, ) *SubscriptionGroupResponse`

NewSubscriptionGroupResponse instantiates a new SubscriptionGroupResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionGroupResponseWithDefaults

`func NewSubscriptionGroupResponseWithDefaults() *SubscriptionGroupResponse`

NewSubscriptionGroupResponseWithDefaults instantiates a new SubscriptionGroupResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionGroupResponse) GetData() SubscriptionGroup`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionGroupResponse) GetDataOk() (*SubscriptionGroup, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionGroupResponse) SetData(v SubscriptionGroup)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionGroupResponse) GetIncluded() []SubscriptionGroupsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionGroupResponse) GetIncludedOk() (*[]SubscriptionGroupsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionGroupResponse) SetIncluded(v []SubscriptionGroupsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionGroupResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionGroupResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionGroupResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionGroupResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


