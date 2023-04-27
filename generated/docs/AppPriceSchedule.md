# AppPriceSchedule

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Relationships** | Pointer to [**AppPriceScheduleRelationships**](AppPriceScheduleRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppPriceSchedule

`func NewAppPriceSchedule(type_ string, id string, links ResourceLinks, ) *AppPriceSchedule`

NewAppPriceSchedule instantiates a new AppPriceSchedule object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPriceScheduleWithDefaults

`func NewAppPriceScheduleWithDefaults() *AppPriceSchedule`

NewAppPriceScheduleWithDefaults instantiates a new AppPriceSchedule object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppPriceSchedule) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppPriceSchedule) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppPriceSchedule) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppPriceSchedule) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppPriceSchedule) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppPriceSchedule) SetId(v string)`

SetId sets Id field to given value.


### GetRelationships

`func (o *AppPriceSchedule) GetRelationships() AppPriceScheduleRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppPriceSchedule) GetRelationshipsOk() (*AppPriceScheduleRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppPriceSchedule) SetRelationships(v AppPriceScheduleRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppPriceSchedule) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppPriceSchedule) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPriceSchedule) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPriceSchedule) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


