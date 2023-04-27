# InAppPurchasePriceScheduleResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**InAppPurchasePriceAttributes**](InAppPurchasePriceAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchasePriceRelationships**](InAppPurchasePriceRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewInAppPurchasePriceScheduleResponseIncludedInner

`func NewInAppPurchasePriceScheduleResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *InAppPurchasePriceScheduleResponseIncludedInner`

NewInAppPurchasePriceScheduleResponseIncludedInner instantiates a new InAppPurchasePriceScheduleResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasePriceScheduleResponseIncludedInnerWithDefaults

`func NewInAppPurchasePriceScheduleResponseIncludedInnerWithDefaults() *InAppPurchasePriceScheduleResponseIncludedInner`

NewInAppPurchasePriceScheduleResponseIncludedInnerWithDefaults instantiates a new InAppPurchasePriceScheduleResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetAttributes() InAppPurchasePriceAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetAttributesOk() (*InAppPurchasePriceAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) SetAttributes(v InAppPurchasePriceAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetRelationships() InAppPurchasePriceRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetRelationshipsOk() (*InAppPurchasePriceRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) SetRelationships(v InAppPurchasePriceRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchasePriceScheduleResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


