# BetaGroupsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**BetaTesterAttributes**](BetaTesterAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**BetaTesterRelationships**](BetaTesterRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewBetaGroupsResponseIncludedInner

`func NewBetaGroupsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *BetaGroupsResponseIncludedInner`

NewBetaGroupsResponseIncludedInner instantiates a new BetaGroupsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBetaGroupsResponseIncludedInnerWithDefaults

`func NewBetaGroupsResponseIncludedInnerWithDefaults() *BetaGroupsResponseIncludedInner`

NewBetaGroupsResponseIncludedInnerWithDefaults instantiates a new BetaGroupsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *BetaGroupsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *BetaGroupsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *BetaGroupsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *BetaGroupsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *BetaGroupsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *BetaGroupsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *BetaGroupsResponseIncludedInner) GetAttributes() BetaTesterAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *BetaGroupsResponseIncludedInner) GetAttributesOk() (*BetaTesterAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *BetaGroupsResponseIncludedInner) SetAttributes(v BetaTesterAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *BetaGroupsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *BetaGroupsResponseIncludedInner) GetRelationships() BetaTesterRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *BetaGroupsResponseIncludedInner) GetRelationshipsOk() (*BetaTesterRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *BetaGroupsResponseIncludedInner) SetRelationships(v BetaTesterRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *BetaGroupsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *BetaGroupsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *BetaGroupsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *BetaGroupsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


