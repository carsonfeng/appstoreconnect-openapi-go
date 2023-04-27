# \AppStoreVersionPromotionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppStoreVersionPromotionsCreateInstance**](AppStoreVersionPromotionsApi.md#AppStoreVersionPromotionsCreateInstance) | **Post** /v1/appStoreVersionPromotions | 



## AppStoreVersionPromotionsCreateInstance

> AppStoreVersionPromotionResponse AppStoreVersionPromotionsCreateInstance(ctx).AppStoreVersionPromotionCreateRequest(appStoreVersionPromotionCreateRequest).Execute()



### Example

```go
package main

import (
    "context"
    "fmt"
    "os"
    openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID"
)

func main() {
    appStoreVersionPromotionCreateRequest := *openapiclient.NewAppStoreVersionPromotionCreateRequest(*openapiclient.NewAppStoreVersionPromotionCreateRequestData("Type_example", *openapiclient.NewAppStoreVersionPromotionCreateRequestDataRelationships(*openapiclient.NewAppStoreReviewDetailCreateRequestDataRelationshipsAppStoreVersion(*openapiclient.NewAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData("Type_example", "Id_example")), *openapiclient.NewAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationshipsAppStoreVersionExperimentTreatment(*openapiclient.NewAppStoreVersionExperimentTreatmentLocalizationRelationshipsAppStoreVersionExperimentTreatmentData("Type_example", "Id_example"))))) // AppStoreVersionPromotionCreateRequest | AppStoreVersionPromotion representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionPromotionsApi.AppStoreVersionPromotionsCreateInstance(context.Background()).AppStoreVersionPromotionCreateRequest(appStoreVersionPromotionCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionPromotionsApi.AppStoreVersionPromotionsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionPromotionsCreateInstance`: AppStoreVersionPromotionResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionPromotionsApi.AppStoreVersionPromotionsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionPromotionsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appStoreVersionPromotionCreateRequest** | [**AppStoreVersionPromotionCreateRequest**](AppStoreVersionPromotionCreateRequest.md) | AppStoreVersionPromotion representation | 

### Return type

[**AppStoreVersionPromotionResponse**](AppStoreVersionPromotionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

