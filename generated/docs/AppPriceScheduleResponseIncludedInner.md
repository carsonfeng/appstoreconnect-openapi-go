# AppPriceScheduleResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppPriceV2Attributes**](AppPriceV2Attributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppPriceV2Relationships**](AppPriceV2Relationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppPriceScheduleResponseIncludedInner

`func NewAppPriceScheduleResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppPriceScheduleResponseIncludedInner`

NewAppPriceScheduleResponseIncludedInner instantiates a new AppPriceScheduleResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPriceScheduleResponseIncludedInnerWithDefaults

`func NewAppPriceScheduleResponseIncludedInnerWithDefaults() *AppPriceScheduleResponseIncludedInner`

NewAppPriceScheduleResponseIncludedInnerWithDefaults instantiates a new AppPriceScheduleResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppPriceScheduleResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppPriceScheduleResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppPriceScheduleResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppPriceScheduleResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppPriceScheduleResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppPriceScheduleResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppPriceScheduleResponseIncludedInner) GetAttributes() AppPriceV2Attributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppPriceScheduleResponseIncludedInner) GetAttributesOk() (*AppPriceV2Attributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppPriceScheduleResponseIncludedInner) SetAttributes(v AppPriceV2Attributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppPriceScheduleResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppPriceScheduleResponseIncludedInner) GetRelationships() AppPriceV2Relationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppPriceScheduleResponseIncludedInner) GetRelationshipsOk() (*AppPriceV2Relationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppPriceScheduleResponseIncludedInner) SetRelationships(v AppPriceV2Relationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppPriceScheduleResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppPriceScheduleResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPriceScheduleResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPriceScheduleResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


