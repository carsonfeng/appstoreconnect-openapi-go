# AppAvailabilityResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**TerritoryAttributes**](TerritoryAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppRelationships**](AppRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppAvailabilityResponseIncludedInner

`func NewAppAvailabilityResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppAvailabilityResponseIncludedInner`

NewAppAvailabilityResponseIncludedInner instantiates a new AppAvailabilityResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppAvailabilityResponseIncludedInnerWithDefaults

`func NewAppAvailabilityResponseIncludedInnerWithDefaults() *AppAvailabilityResponseIncludedInner`

NewAppAvailabilityResponseIncludedInnerWithDefaults instantiates a new AppAvailabilityResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppAvailabilityResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppAvailabilityResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppAvailabilityResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppAvailabilityResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppAvailabilityResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppAvailabilityResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppAvailabilityResponseIncludedInner) GetAttributes() TerritoryAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppAvailabilityResponseIncludedInner) GetAttributesOk() (*TerritoryAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppAvailabilityResponseIncludedInner) SetAttributes(v TerritoryAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppAvailabilityResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppAvailabilityResponseIncludedInner) GetRelationships() AppRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppAvailabilityResponseIncludedInner) GetRelationshipsOk() (*AppRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppAvailabilityResponseIncludedInner) SetRelationships(v AppRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppAvailabilityResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppAvailabilityResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppAvailabilityResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppAvailabilityResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


