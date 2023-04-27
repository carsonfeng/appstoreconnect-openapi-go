# AppStoreVersionReleaseRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppStoreVersionReleaseRequest

`func NewAppStoreVersionReleaseRequest(type_ string, id string, links ResourceLinks, ) *AppStoreVersionReleaseRequest`

NewAppStoreVersionReleaseRequest instantiates a new AppStoreVersionReleaseRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionReleaseRequestWithDefaults

`func NewAppStoreVersionReleaseRequestWithDefaults() *AppStoreVersionReleaseRequest`

NewAppStoreVersionReleaseRequestWithDefaults instantiates a new AppStoreVersionReleaseRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppStoreVersionReleaseRequest) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppStoreVersionReleaseRequest) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppStoreVersionReleaseRequest) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppStoreVersionReleaseRequest) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppStoreVersionReleaseRequest) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppStoreVersionReleaseRequest) SetId(v string)`

SetId sets Id field to given value.


### GetLinks

`func (o *AppStoreVersionReleaseRequest) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionReleaseRequest) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionReleaseRequest) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


