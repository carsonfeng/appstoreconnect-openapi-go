# AppPricePointsV2ResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**TerritoryAttributes**](TerritoryAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppPriceTierRelationships**](AppPriceTierRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppPricePointsV2ResponseIncludedInner

`func NewAppPricePointsV2ResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppPricePointsV2ResponseIncludedInner`

NewAppPricePointsV2ResponseIncludedInner instantiates a new AppPricePointsV2ResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPricePointsV2ResponseIncludedInnerWithDefaults

`func NewAppPricePointsV2ResponseIncludedInnerWithDefaults() *AppPricePointsV2ResponseIncludedInner`

NewAppPricePointsV2ResponseIncludedInnerWithDefaults instantiates a new AppPricePointsV2ResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppPricePointsV2ResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppPricePointsV2ResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppPricePointsV2ResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppPricePointsV2ResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppPricePointsV2ResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppPricePointsV2ResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppPricePointsV2ResponseIncludedInner) GetAttributes() TerritoryAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppPricePointsV2ResponseIncludedInner) GetAttributesOk() (*TerritoryAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppPricePointsV2ResponseIncludedInner) SetAttributes(v TerritoryAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppPricePointsV2ResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppPricePointsV2ResponseIncludedInner) GetRelationships() AppPriceTierRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppPricePointsV2ResponseIncludedInner) GetRelationshipsOk() (*AppPriceTierRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppPricePointsV2ResponseIncludedInner) SetRelationships(v AppPriceTierRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppPricePointsV2ResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppPricePointsV2ResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPricePointsV2ResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPricePointsV2ResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


