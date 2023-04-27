# AppPricePointV3Relationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**App** | Pointer to [**AppAvailabilityRelationshipsApp**](AppAvailabilityRelationshipsApp.md) |  | [optional] 
**Territory** | Pointer to [**AppPricePointV2RelationshipsTerritory**](AppPricePointV2RelationshipsTerritory.md) |  | [optional] 

## Methods

### NewAppPricePointV3Relationships

`func NewAppPricePointV3Relationships() *AppPricePointV3Relationships`

NewAppPricePointV3Relationships instantiates a new AppPricePointV3Relationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPricePointV3RelationshipsWithDefaults

`func NewAppPricePointV3RelationshipsWithDefaults() *AppPricePointV3Relationships`

NewAppPricePointV3RelationshipsWithDefaults instantiates a new AppPricePointV3Relationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetApp

`func (o *AppPricePointV3Relationships) GetApp() AppAvailabilityRelationshipsApp`

GetApp returns the App field if non-nil, zero value otherwise.

### GetAppOk

`func (o *AppPricePointV3Relationships) GetAppOk() (*AppAvailabilityRelationshipsApp, bool)`

GetAppOk returns a tuple with the App field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetApp

`func (o *AppPricePointV3Relationships) SetApp(v AppAvailabilityRelationshipsApp)`

SetApp sets App field to given value.

### HasApp

`func (o *AppPricePointV3Relationships) HasApp() bool`

HasApp returns a boolean if a field has been set.

### GetTerritory

`func (o *AppPricePointV3Relationships) GetTerritory() AppPricePointV2RelationshipsTerritory`

GetTerritory returns the Territory field if non-nil, zero value otherwise.

### GetTerritoryOk

`func (o *AppPricePointV3Relationships) GetTerritoryOk() (*AppPricePointV2RelationshipsTerritory, bool)`

GetTerritoryOk returns a tuple with the Territory field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTerritory

`func (o *AppPricePointV3Relationships) SetTerritory(v AppPricePointV2RelationshipsTerritory)`

SetTerritory sets Territory field to given value.

### HasTerritory

`func (o *AppPricePointV3Relationships) HasTerritory() bool`

HasTerritory returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


