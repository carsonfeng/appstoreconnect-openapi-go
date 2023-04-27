# AppEventLocalization

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppEventLocalizationAttributes**](AppEventLocalizationAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppEventLocalizationRelationships**](AppEventLocalizationRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppEventLocalization

`func NewAppEventLocalization(type_ string, id string, links ResourceLinks, ) *AppEventLocalization`

NewAppEventLocalization instantiates a new AppEventLocalization object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventLocalizationWithDefaults

`func NewAppEventLocalizationWithDefaults() *AppEventLocalization`

NewAppEventLocalizationWithDefaults instantiates a new AppEventLocalization object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppEventLocalization) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppEventLocalization) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppEventLocalization) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppEventLocalization) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppEventLocalization) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppEventLocalization) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppEventLocalization) GetAttributes() AppEventLocalizationAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppEventLocalization) GetAttributesOk() (*AppEventLocalizationAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppEventLocalization) SetAttributes(v AppEventLocalizationAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppEventLocalization) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppEventLocalization) GetRelationships() AppEventLocalizationRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppEventLocalization) GetRelationshipsOk() (*AppEventLocalizationRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppEventLocalization) SetRelationships(v AppEventLocalizationRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppEventLocalization) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventLocalization) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventLocalization) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventLocalization) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


