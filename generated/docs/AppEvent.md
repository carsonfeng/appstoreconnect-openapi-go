# AppEvent

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppEventAttributes**](AppEventAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppEventRelationships**](AppEventRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppEvent

`func NewAppEvent(type_ string, id string, links ResourceLinks, ) *AppEvent`

NewAppEvent instantiates a new AppEvent object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventWithDefaults

`func NewAppEventWithDefaults() *AppEvent`

NewAppEventWithDefaults instantiates a new AppEvent object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppEvent) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppEvent) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppEvent) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppEvent) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppEvent) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppEvent) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppEvent) GetAttributes() AppEventAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppEvent) GetAttributesOk() (*AppEventAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppEvent) SetAttributes(v AppEventAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppEvent) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppEvent) GetRelationships() AppEventRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppEvent) GetRelationshipsOk() (*AppEventRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppEvent) SetRelationships(v AppEventRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppEvent) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppEvent) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEvent) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEvent) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


