# AppCustomProductPageCreateRequestIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | Pointer to **string** |  | [optional] 
**Attributes** | [**AppCustomProductPageLocalizationInlineCreateAttributes**](AppCustomProductPageLocalizationInlineCreateAttributes.md) |  | 
**Relationships** | Pointer to [**AppCustomProductPageVersionInlineCreateRelationships**](AppCustomProductPageVersionInlineCreateRelationships.md) |  | [optional] 

## Methods

### NewAppCustomProductPageCreateRequestIncludedInner

`func NewAppCustomProductPageCreateRequestIncludedInner(type_ string, attributes AppCustomProductPageLocalizationInlineCreateAttributes, ) *AppCustomProductPageCreateRequestIncludedInner`

NewAppCustomProductPageCreateRequestIncludedInner instantiates a new AppCustomProductPageCreateRequestIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppCustomProductPageCreateRequestIncludedInnerWithDefaults

`func NewAppCustomProductPageCreateRequestIncludedInnerWithDefaults() *AppCustomProductPageCreateRequestIncludedInner`

NewAppCustomProductPageCreateRequestIncludedInnerWithDefaults instantiates a new AppCustomProductPageCreateRequestIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppCustomProductPageCreateRequestIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppCustomProductPageCreateRequestIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppCustomProductPageCreateRequestIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppCustomProductPageCreateRequestIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppCustomProductPageCreateRequestIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppCustomProductPageCreateRequestIncludedInner) SetId(v string)`

SetId sets Id field to given value.

### HasId

`func (o *AppCustomProductPageCreateRequestIncludedInner) HasId() bool`

HasId returns a boolean if a field has been set.

### GetAttributes

`func (o *AppCustomProductPageCreateRequestIncludedInner) GetAttributes() AppCustomProductPageLocalizationInlineCreateAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppCustomProductPageCreateRequestIncludedInner) GetAttributesOk() (*AppCustomProductPageLocalizationInlineCreateAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppCustomProductPageCreateRequestIncludedInner) SetAttributes(v AppCustomProductPageLocalizationInlineCreateAttributes)`

SetAttributes sets Attributes field to given value.


### GetRelationships

`func (o *AppCustomProductPageCreateRequestIncludedInner) GetRelationships() AppCustomProductPageVersionInlineCreateRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppCustomProductPageCreateRequestIncludedInner) GetRelationshipsOk() (*AppCustomProductPageVersionInlineCreateRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppCustomProductPageCreateRequestIncludedInner) SetRelationships(v AppCustomProductPageVersionInlineCreateRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppCustomProductPageCreateRequestIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


