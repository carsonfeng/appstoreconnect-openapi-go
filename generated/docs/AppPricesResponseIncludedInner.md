# AppPricesResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppAttributes**](AppAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppPriceTierRelationships**](AppPriceTierRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppPricesResponseIncludedInner

`func NewAppPricesResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppPricesResponseIncludedInner`

NewAppPricesResponseIncludedInner instantiates a new AppPricesResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPricesResponseIncludedInnerWithDefaults

`func NewAppPricesResponseIncludedInnerWithDefaults() *AppPricesResponseIncludedInner`

NewAppPricesResponseIncludedInnerWithDefaults instantiates a new AppPricesResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppPricesResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppPricesResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppPricesResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppPricesResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppPricesResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppPricesResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppPricesResponseIncludedInner) GetAttributes() AppAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppPricesResponseIncludedInner) GetAttributesOk() (*AppAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppPricesResponseIncludedInner) SetAttributes(v AppAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppPricesResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppPricesResponseIncludedInner) GetRelationships() AppPriceTierRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppPricesResponseIncludedInner) GetRelationshipsOk() (*AppPriceTierRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppPricesResponseIncludedInner) SetRelationships(v AppPriceTierRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppPricesResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppPricesResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPricesResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPricesResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


