# CiMacOsVersionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**CiMacOsVersion**](CiMacOsVersion.md) |  | 
**Included** | Pointer to [**[]CiXcodeVersion**](CiXcodeVersion.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewCiMacOsVersionResponse

`func NewCiMacOsVersionResponse(data CiMacOsVersion, links DocumentLinks, ) *CiMacOsVersionResponse`

NewCiMacOsVersionResponse instantiates a new CiMacOsVersionResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiMacOsVersionResponseWithDefaults

`func NewCiMacOsVersionResponseWithDefaults() *CiMacOsVersionResponse`

NewCiMacOsVersionResponseWithDefaults instantiates a new CiMacOsVersionResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiMacOsVersionResponse) GetData() CiMacOsVersion`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiMacOsVersionResponse) GetDataOk() (*CiMacOsVersion, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiMacOsVersionResponse) SetData(v CiMacOsVersion)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiMacOsVersionResponse) GetIncluded() []CiXcodeVersion`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiMacOsVersionResponse) GetIncludedOk() (*[]CiXcodeVersion, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiMacOsVersionResponse) SetIncluded(v []CiXcodeVersion)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiMacOsVersionResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiMacOsVersionResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiMacOsVersionResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiMacOsVersionResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


