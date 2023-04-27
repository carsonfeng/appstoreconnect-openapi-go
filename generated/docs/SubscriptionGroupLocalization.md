# SubscriptionGroupLocalization

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionGroupLocalizationAttributes**](SubscriptionGroupLocalizationAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionGroupLocalizationRelationships**](SubscriptionGroupLocalizationRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionGroupLocalization

`func NewSubscriptionGroupLocalization(type_ string, id string, links ResourceLinks, ) *SubscriptionGroupLocalization`

NewSubscriptionGroupLocalization instantiates a new SubscriptionGroupLocalization object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionGroupLocalizationWithDefaults

`func NewSubscriptionGroupLocalizationWithDefaults() *SubscriptionGroupLocalization`

NewSubscriptionGroupLocalizationWithDefaults instantiates a new SubscriptionGroupLocalization object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionGroupLocalization) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionGroupLocalization) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionGroupLocalization) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionGroupLocalization) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionGroupLocalization) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionGroupLocalization) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionGroupLocalization) GetAttributes() SubscriptionGroupLocalizationAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionGroupLocalization) GetAttributesOk() (*SubscriptionGroupLocalizationAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionGroupLocalization) SetAttributes(v SubscriptionGroupLocalizationAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionGroupLocalization) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionGroupLocalization) GetRelationships() SubscriptionGroupLocalizationRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionGroupLocalization) GetRelationshipsOk() (*SubscriptionGroupLocalizationRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionGroupLocalization) SetRelationships(v SubscriptionGroupLocalizationRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionGroupLocalization) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionGroupLocalization) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionGroupLocalization) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionGroupLocalization) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


