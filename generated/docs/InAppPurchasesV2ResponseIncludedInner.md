# InAppPurchasesV2ResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**PromotedPurchaseAttributes**](PromotedPurchaseAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchasePriceScheduleRelationships**](InAppPurchasePriceScheduleRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewInAppPurchasesV2ResponseIncludedInner

`func NewInAppPurchasesV2ResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *InAppPurchasesV2ResponseIncludedInner`

NewInAppPurchasesV2ResponseIncludedInner instantiates a new InAppPurchasesV2ResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasesV2ResponseIncludedInnerWithDefaults

`func NewInAppPurchasesV2ResponseIncludedInnerWithDefaults() *InAppPurchasesV2ResponseIncludedInner`

NewInAppPurchasesV2ResponseIncludedInnerWithDefaults instantiates a new InAppPurchasesV2ResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchasesV2ResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchasesV2ResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchasesV2ResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *InAppPurchasesV2ResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InAppPurchasesV2ResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InAppPurchasesV2ResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *InAppPurchasesV2ResponseIncludedInner) GetAttributes() PromotedPurchaseAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *InAppPurchasesV2ResponseIncludedInner) GetAttributesOk() (*PromotedPurchaseAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *InAppPurchasesV2ResponseIncludedInner) SetAttributes(v PromotedPurchaseAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *InAppPurchasesV2ResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *InAppPurchasesV2ResponseIncludedInner) GetRelationships() InAppPurchasePriceScheduleRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchasesV2ResponseIncludedInner) GetRelationshipsOk() (*InAppPurchasePriceScheduleRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchasesV2ResponseIncludedInner) SetRelationships(v InAppPurchasePriceScheduleRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *InAppPurchasesV2ResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchasesV2ResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchasesV2ResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchasesV2ResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


