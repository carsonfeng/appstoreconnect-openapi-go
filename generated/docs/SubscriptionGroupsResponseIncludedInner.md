# SubscriptionGroupsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionGroupLocalizationAttributes**](SubscriptionGroupLocalizationAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionGroupLocalizationRelationships**](SubscriptionGroupLocalizationRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionGroupsResponseIncludedInner

`func NewSubscriptionGroupsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *SubscriptionGroupsResponseIncludedInner`

NewSubscriptionGroupsResponseIncludedInner instantiates a new SubscriptionGroupsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionGroupsResponseIncludedInnerWithDefaults

`func NewSubscriptionGroupsResponseIncludedInnerWithDefaults() *SubscriptionGroupsResponseIncludedInner`

NewSubscriptionGroupsResponseIncludedInnerWithDefaults instantiates a new SubscriptionGroupsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionGroupsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionGroupsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionGroupsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionGroupsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionGroupsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionGroupsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionGroupsResponseIncludedInner) GetAttributes() SubscriptionGroupLocalizationAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionGroupsResponseIncludedInner) GetAttributesOk() (*SubscriptionGroupLocalizationAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionGroupsResponseIncludedInner) SetAttributes(v SubscriptionGroupLocalizationAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionGroupsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionGroupsResponseIncludedInner) GetRelationships() SubscriptionGroupLocalizationRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionGroupsResponseIncludedInner) GetRelationshipsOk() (*SubscriptionGroupLocalizationRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionGroupsResponseIncludedInner) SetRelationships(v SubscriptionGroupLocalizationRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionGroupsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionGroupsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionGroupsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionGroupsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


